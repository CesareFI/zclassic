<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Bounded C23 intake for transparent ZCL transactions

Local time: 2026-09-27T00:38:40-04:00

UTC: 2026-09-27T04:38:40Z

## Question

Can one C23 parser consume a transaction in arbitrary chunks while retaining
only a small fixed state and rejecting unsupported wire structures before a
future Blue payment review uses its facts?

## Method and result

The new `zcl_tx_stream` library accepts unsigned, all-transparent Sapling-v4
wire bytes with at most 16 inputs, 65,536 standard P2PKH/P2SH outputs, and
2 MiB total length. A C23 `static_assert` caps parser state at 160 bytes.
The ARM compiler accepted that bound; the isolated parser object measured
2,092 bytes of `.text`, zero `.data`, zero `.bss`, and a 40-byte `feed` frame.
These are object measurements, not the cost of integration into the Wallet.

Tests feed a one-input, two-output fixture at every chunk width from one byte
through the fixture length and compare accepted aggregate facts with the
complete transaction parser. They reject truncation at every byte, trailing
bytes, noncanonical CompactSize, callback rejection, nonempty input script,
unsupported output script, out-of-range input count, nonzero value balance,
and nonzero shielded counts. A deterministic 20,000-mutation test compares
accepted streams with the complete parser. The Clang libFuzzer target ran
20,000 inputs from the synthetic fixture with `-seed=2432026 -runs=20000
-max_len=512 -timeout=2`, with no sanitizer finding. Its final instrumentation
reported `cov: 545` and `ft: 1083`; these are fuzzer counters, not coverage
percentages. The complete Ledger host suite passed 20/20 tests under both
Clang Debug with AddressSanitizer and UndefinedBehaviorSanitizer and GCC
Release. The repository cyclomatic gate passed at cap 15: 60,135 functions
in 4,387 files, with 4,113 baseline pins exact.

Clang 22.1.6 and GCC 16.1.1 ran on AMD Ryzen 7 PRO 8840U. The Blue builds used
the pinned open-source SDK and ARM toolchain from `DEVELOPMENT.md`. Rebuilding
both device apps after the common Base58 complexity cleanup left their code
images unchanged: Wallet `.text` 14,848 bytes, `.bss` 3,348 bytes, `.data` 0,
SHA-256 `baf36150563cecd659692434800d5bb106a9679a9fa6e36598a3e38fb0836df2`;
Review `.text` 32,256 bytes, `.bss` 6,000 bytes, `.data` 0, SHA-256
`c7685268f58f5913196f1b9a1547484a9fe8be7f14355325d9e6745f1a3e39eb`.
Both stack gates passed. Neither app image includes the new stream parser.

## Boundary and next test

Callbacks expose provisional facts before final validation; they must never
authorize payment or persist facts without successful `finish`. This parser
does not verify previous outputs, chain inclusion, ZIP-243, change, ownership,
fee, or signatures. Next, a payment review design must bind streamed bytes to
device-computed transaction and input digests, prove prevout amounts and
scripts, derive change from the device account, and present every output and
fee before explicit approval. Its integrated ARM image needs a fresh SRAM,
stack, simulator, fuzz, and physical Blue check.

The later same-day complexity refactor kept parser behavior under the
repository's cyclomatic cap. Its recompiled ARM object measured 2,168 bytes
of `.text`, zero `.data`, and zero `.bss`. The original 2,092-byte object
measurement above remains the measurement for the earlier source revision.
