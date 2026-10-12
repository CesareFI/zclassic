<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Canary timestamp freshness admission

Base: `1fc6b64b606a19a71ae55198fcfa3462124e9529`.

The MVP gate previously admitted a future canary timestamp because its negative
age satisfied the maximum-age comparison. Numeric-prefix extraction also let
malformed timestamp tokens reach arithmetic, and leading zeros selected shell
octal interpretation. This slice restricts timestamp, observation time, and
configured maximum age to canonical nonnegative decimal values within the
signed 64-bit range before conversion. A qualifying timestamp must be positive
and no later than the observation time. The configured maximum age remains
inclusive; its default remains 604800 seconds.

The gate requires the existing native `build/bin/jsonq`, or an explicit
`ZCL_JSONQ` path. Missing parser availability leaves freshness and identities
unqualified and reports an unavailable verdict with a diagnostic. There is no
regular-expression fallback. The parser reads the sentinel once, validates
exactly one JSON document within its existing 16 MiB input bound, and supplies
a validated snapshot. Only unique, direct root fields of the expected types
qualify timestamp, verdict, source identity, and artifact identity. Verdicts
must be literal `PASS`, `FAIL`, `BLOCKED`, or `UNKNOWN`; identities must be
literal 64-character lowercase hexadecimal strings. Escaped string tokens
are refused before shell substitution can remove decoded NUL or trailing
newline bytes. This avoids
both embedded-string spoofing and mixed observations across atomic replacements.

The registered `replay_canary_verdict` group adds a C23 fixture that extracts
the actual `canary_decimal`, `canary_field`, and `canary_read` function bodies from
the production gate. It executes only those functions in a private directory
through the bounded process API. It does not source the complete gate, contact
RPC endpoints, start services, or touch operator verdict files.

Twenty-four freshness cases cover current time, the inclusive seven-day boundary, expiry,
future time, zero, leading zero, malformed numeric suffix, exponent notation,
quoted number, negative value, two oversized values, the signed maximum,
custom inclusive and expired boundaries, and invalid observation/configuration
decimals, escaped-string timestamp spoofing, nested and duplicate timestamps,
non-object roots, incomplete JSON, embedded NUL, and oversized parser input.
Nine identity cases cover valid PASS and FAIL fields, escaped-string spoofing,
duplicate identities and verdicts, trailing and interior escaped NUL, trailing
escaped newline, and escaped NUL in the verdict. A missing-parser case requires an
unavailable verdict with empty identities. The canonical group build-needs
table builds `jsonq` before the fixture runs.
The future case requires freshness zero and uncomputed age minus one.
This tests freshness admission only; it does not qualify C8's continuous parity
window or change replay failure authority.

Source checks: `bash -n tools/mvp_gate.sh` and `git diff --check` passed.
Independent source review accepted the literal-token slice. Linux focused
qualification completed as recorded below. Native macOS qualification is
pending in an admitted isolated checkout; no portable runtime result is claimed
until that registered run completes.

An initial admitted Linux run on base
`cc40bab787ea1d3e43ed1fce91a008db8404bd47` qualified only the prior timestamp
slice: fixed passed one cold group in 48.1 seconds, the original-arithmetic
mutation failed one group in 30.8 seconds including the future case, and
restoration passed one group in 42.5 seconds. All three runs had zero cached
groups and zero self-skips. The compiler was GCC 14.2.0 on an AMD Ryzen 9
7950X3D; execution began at 2026-10-08T12:46:56Z with 28 workers.
The old gate hash was
`21708e36e636595f58bde0490770a3de822993d0a8bef5dca72796b166bc610e`.
That source decoded identity strings and did not close the escaped-control-byte
boundary. These observations are historical evidence, not qualification of
the revised literal-token admission or the complete C8 criterion.

## Literal-token Linux qualification

The revised admitted run began at 2026-10-08T13:00:52Z on the same `cc40bab787`
base with GCC 14.2.0, AMD Ryzen 9 7950X3D, and the installed 28-worker/24-GiB
development preset. Every phase executed the exact registered
`replay_canary_verdict` group with cache disabled: one group ran, 1259 were
outside the selector, and there were zero skips, unobserved environments, or
load-flaky outcomes.

| Source state | Outcome | Wall seconds |
| --- | --- | ---: |
| Fixed literal-token source | PASS | 29.4 |
| Original timestamp arithmetic admission | Expected FAIL | 42.1 |
| Decoded identity getter admission | Expected FAIL | 18.9 |
| Exact fixed-source restoration | PASS | 60.6 |

The arithmetic mutation restored the production gate's positive-timestamp-only
condition. The future fixture observed freshness one with age minus one. The
second mutation restored decoded string getters after unique-key/type checks;
trailing escaped NUL and newline fixtures then observed the exact expected
hashes with a PASS verdict. Restoring the fixed gate between mutations prevented
one defect from masking the other. The final registered pass followed exact
restoration, and `git diff --check` passed.

Tested gate SHA-256:
`c666eaf8f1e0c26b53970f89a92cd0050e3e66b61f6a04d1ca1eaf59d7ca79e5`.
Test fixture SHA-256:
`5f83d96af4218f31147e718babe04487e21d69b79aa9a06cb043fa3602770adc`.
Runner SHA-256:
`505ae98267792406b5c9f21f8b0333004ef281b1f2126f576a6c912d34bc2dec`.
Native parser SHA-256:
`3e269455046ed39c7d82efdc872e28b05736026e4a17195c448ed44682c18c34`.

The private fixed, arithmetic-mutated, decoded-mutated, and restored log exports
have SHA-256 roots respectively:
`3fcc79315403ff444ef0966306962c910a818ac60989c8d2cdbf187b74a06fd8`,
`f92e8d4e09d329232c88d931046f45c43f69b15f78881bc58a4c415968ae02da`,
`9b649a60d8457dbf2403f5967f1769307f45d82566c1a1a58ed40c1be7ebece7`,
`3a50451a6a843fcd4e1ac758281aaed961593c2652ca82fead397524fa023a64`.
These hashes identify retained evidence bytes; they do not alone qualify a
computation or the complete C8 parity window.
