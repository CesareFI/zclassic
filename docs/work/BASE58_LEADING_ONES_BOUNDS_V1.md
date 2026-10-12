<!-- Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0 -->
# Base58 whole-string leading-one bound V1

First command UTC2026-10-04T22:00:32Z. Assigned input review SHA256772fc171426ac4230163d0b8ba5153896944e85ce11580b6b3da81170a669a1c identifies the inherited whole-string bound defect. Native fresh lane base db648476e77c14308d77501ad85655e2444043b3; exact PR74 base58 blob aba6079cae62b4035c90f29e4d4ccb7050353d42. Contributor code and credit remain unchanged beyond this separate bounded repair.

Tests were written before production edits. Actual canonical cold domain_encoding_base58 returned behavioral RED: the two1024-character vectors (all leading ones and1023 ones followed by2) were accepted; group failed1/cache0/skip0. Four other new checks passed:1023 ones with exact capacity and guards; capacities0/1022 with no byte publication;1022 ones plus2 with exact decoded zeros/magnitude. Over-limit refusal must preserve both the complete destination buffer and prior length value. Valid-input capacity refusal retains the existing required-length reporting contract while preserving every output byte.

Fix: bounded scan of the whole NUL-terminated string before whitespace/leading-one counting, refusal above1023, size_t leading-zero counter. At most1024 input bytes are examined before oversized refusal. The later suffix scan/scratch algorithm remains intact. A run of INT_MAX+1 leading ones is now refused at the small bound before counting; no multi-gigabyte runtime experiment was executed. Ordinary documented whitespace handling remains accepted within the whole-string cap. No output is written at the early length failure.

First changed-source cold group passed158 assertions/1group/0fail/cache/skip. Required lint initially RED on newly authored test complexity18; over-limit cases were split into a separate function without assertion/cap/baseline changes. The same affected cold group was run again on the split fixture. Exact final receipts/logs accompany the immutable packet; lint-fast final disposition is in its report.

Commands, always through native source/build locks and devbuild:

```
devbuild --wait make -j"$(getconf _NPROCESSORS_ONLN)" t-fast-exact ONLY=domain_encoding_base58
devbuild --wait make -j"$(getconf _NPROCESSORS_ONLN)" lint-fast
```

No push, proof, landing, core/custody or installed-state action. This packet is a tested proposal on top of the exact maintainer source base, not a public release or acceptance of unrelated pending integration gates.
