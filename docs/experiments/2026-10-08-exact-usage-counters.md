<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Exact usage counters and visible incomplete hourly totals

## Contract

The usage importer admits nonnegative integer-encoded `int64_t` counters.
Real-valued JSON tokens remain unreported, including integral-looking decimal
and exponent forms. The JSON parser retains a double rather than the original
token spelling; a double-to-integer round trip cannot prove token exactness.
For example, a fractional token near 42 or the binary64 precision boundary
can round to an integer before admission.

Hourly summaries now include the existing per-field `unreported` object,
matching model summaries. Totals contain known observations only; the metadata
identifies incomplete coverage. An absent counter is not measured zero.
This change does not establish complete task attribution or financial cost.

## Qualification

Source base: `ed3b192029bbe4fc9df534a26fb021cc84993f6d`.
On 2026-10-08T20:42:30Z, the isolated development lane used GCC 14.2.0 on an
AMD Ryzen 9 7950X3D. The canonical host-admitted command was
`devbuild --wait make -j28 t-fast-exact ONLY=devagent_outcomes`.

The production-importer fixture covers integer zero, 42 and `INT64_MAX`;
decimal, exponent and rounded fractional tokens; negative, null and absent
counters. Unknown cases include a measured sentinel value of seven, checking
that both model and hourly totals preserve known measurements and expose
unknown coverage separately.

The initial run failed all 60 new cases because hourly summaries omitted
`unreported`. After using the existing serializer for that metadata, the
registered group passed with zero failures and zero skips. Reintroducing the
original real-to-integer conversion produced 24 assertion failures and make
exit 2. Reversing that exact mutation restored the source hash and the group
passed again with zero failures and zero skips (0.1 seconds test wall time).

Restored source SHA-256:
`105b6dbdde54279fc0d063c36cce95f233047c2e5310d95478943c409185bbec`.
Fixture SHA-256:
`ecb3816b990952c4e1e53058bd14d528f3e4bd0b47cea40be3c3500d83daf6f9`.
Logs are retained in the owning lane as `build/exact-usage-test.log`,
`build/exact-usage-test-v2.log`, `build/exact-usage-mutation.log` and
`build/exact-usage-restored.log`.

Independent source review accepted the exact restored bytes above. Focused lint passed. The inline hourly schema was then corrected to name the additive unreported object; this documentation-only correction does not change counter behavior. Full exact publication proof remains pending.

After the inline schema correction, the canonical focused group passed again
with zero failed groups and zero skipped tests. The final run is retained in
`build/exact-usage-final.log`; its test body took 48 ms. This does not replace
the earlier mutation evidence or qualify the subsequent integration pair.
