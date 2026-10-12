<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue Wallet 0.3.6 stack-path audit

Local time: 2026-09-27T22:36:41-04:00.
UTC: 2026-09-28T02:36:41Z.

The Wallet's named-frame checker omitted the 304-byte `main` frame from
payment, signing, and event paths. That frame remains live while `main` calls
the APDU loop. The checker now includes it in those paths, includes the
`io_exchange` frame in USB event and touch paths, and accounts for the largest
measured SDK wrapper on each startup derivation and public-hash route.

Clang 22.1.6 and GCC 16.1.1 built the checker with `-std=c23`, `-Wall`,
`-Wextra`, `-Werror`, and `-pedantic`. The Wallet's existing ARM 16.2.0 GCC
`.su` records, produced from the pinned Blue SDK, yielded a 2,048-byte stack
reserve. The largest named payment-upload path is 1,056 bytes; the largest
named signing path is 1,040 bytes. The startup public-hash path is 496 bytes.
The checker requires a 512-byte margin, so these measured paths pass. The
`check-image` gate also passed: `.text` is 40,960 bytes, `.data` is zero,
and `.bss` is 5,120 bytes, including the reserved stack. The extracted
`.text` still has SHA-256
`435b6f03a62e99daa668b85c71e895f7b64ad7a056b575367c5bf2af460e09c3`.

For a negative test, a copy of the ARM `.su` files changed only `main` from
304 to 900 bytes. The previous checker accepted those records and reported a
maximum named path below its 1,536-byte threshold. The corrected checker
rejected them: the payment-upload path measured 1,652 bytes and the signing
public-hash path measured 1,636 bytes. This demonstrates that the gate now
accounts for a live caller frame that the previous gate missed.

These are sums of named compiled C frames. They exclude BOLOS firmware frames,
interrupt stack use, and dynamically sized frames. Passing them does not
establish that Wallet 0.3.6 will open safely on a physical Blue. The installer
still excludes this image.

The staged C23 cyclomatic checker selftest passed and its repository scan
accepted 63,031 functions in 4,542 files at cap 15, with 4,112 exact
baseline pins. All 50 Ledger CTests passed under Clang Debug with
ASan/UBSan and GCC Release; the CTests do not replace the ARM stack gate.
