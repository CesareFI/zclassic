<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# One-context ZIP-243 replay bound to transaction bytes

Local time: 2026-09-27T00:58:08-04:00

UTC: 2026-09-27T04:58:08Z

## Question

Can three full, identical transaction uploads reduce live BLAKE2b state while
preserving the exact transparent input ZIP-243 digest and rejecting a changed
or interrupted replay?

## Method and result

The C23 `zcl_tx_replay_zip243` session parses each complete unsigned,
all-transparent Sapling-v4 upload with the bounded wire parser. Pass one hashes
prevouts; pass two hashes sequences; pass three hashes canonical standard
outputs and captures the selected input. A streaming SHA-256 hash of every
wire byte in each pass must match the complete first pass before the pass's
subhash is accepted. The session reuses one personalized BLAKE2b context and
returns the input-specific digest only after all three passes validate. Any
malformed, truncated, changed, or out-of-order upload invalidates the session.

The test starts from the published ZIP-243 transparent vector, removes its
107-byte signed input script to form an unsigned fixture, and derives a
reference digest from the existing complete-transaction ZIP-243 library.
Every chunk width from one byte through the unsigned fixture length matches
that digest. Changing one accepted outpoint byte between passes, truncating
an upload, repeating `finish`, or selecting a nonexistent input is rejected;
failed `finish` calls with a non-null state and valid output pointers zero
the output facts and digest. The Clang 22.1.6 Debug sanitizer and GCC 16.1.1
Release host suites passed 20/20 tests on AMD Ryzen 7 PRO 8840U. A Clang
libFuzzer session ran
20,000 inputs and compared accepted replay digests with both the two-context
streaming and complete-transaction implementations without a sanitizer
finding. Its final instrumentation counters were `cov: 9766` and `ft: 10679`,
not coverage percentages. The repository cyclomatic gate passed at cap 15.

ARM GCC 16.2.0 compiled the replay source as ISO C23 with `-Wall -Wextra
-Werror -pedantic -fstack-usage`. The object measured 2,284 bytes of `.text`,
zero `.data`, and zero `.bss`; its largest reported function frame was 176
bytes. ARM type-size symbols measured the replay wrapper at 320 bytes, the
Blue SDK BLAKE2b context at 256 bytes, and its SHA-256 context at 108 bytes.
The 684-byte combined live state saves 116 bytes against the earlier
two-BLAKE2b-context prototype. The original Wallet calculation subtracted
the 2,048-byte stack reserve a second time. The corrected Wallet image leaves
2,796 bytes after `.bss`, and its 512-byte headroom guard permits 2,284 bytes
of additional `.bss`. The isolated replay state fits within that budget;
transport and payment UI state remain unmeasured.

## Boundary

Three uploads increase USB traffic and latency; physical Blue timing has not
been measured. The SHA-256 commitment binds the passes to one transaction,
but does not authenticate previous outputs, chain inclusion, change, account,
fee, consensus branch, or the supplied scriptCode and amount. No device image
includes this session and no payment signing path uses its digest. The next
device experiment must measure storage lifetimes and choose a layout that
passes the full SRAM and stack gates while retaining a responsive, readable
approval screen for every output and fee.
