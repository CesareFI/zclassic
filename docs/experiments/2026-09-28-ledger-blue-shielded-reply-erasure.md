<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue shielded APDU reply erasure

Date: 2026-09-28T16:25:05-04:00; UTC: 2026-09-28T20:25:05+00:00.
Host: AMD Ryzen 7 PRO 8840U with Radeon 780M Graphics. Compiler: Clang
22.1.6. Device linker: ARM GCC 16.2.0. Target: Ledger Blue firmware 2.1.x,
SDK revision `3c710b4c62ad847599a2deb0932a50dd1ae4bdff` with the pinned
C23 patch.

## Failure and correction

The APDU and app controllers previously erased at most 76 bytes of a
rejected reply. The Blue shares request and reply storage, so a rejected
upload could leave request bytes beyond offset 75 available to later code.
The controllers now erase the entire declared reply capacity on rejection
and the unused capacity after a successful response. The controller also
rejects a successful dispatcher result whose reported reply length exceeds
capacity. Callers remain responsible for providing a valid buffer of the
declared capacity and a disjoint reply-length pointer.

Before the correction, assertions that every byte from `reply_length` to
offset 254 was zero failed in both `blue-shielded-review-apdu` and
`blue-shielded-review-app`. After the correction, both focused tests passed.
The final Release suite passed 57/57; the AddressSanitizer and
UndefinedBehaviorSanitizer Debug suite passed 57/57 with
`ASAN_OPTIONS=detect_leaks=0`. The updated local Clang fuzz harness checked
full-capacity erasure and completed 1,000 generated inputs with no finding:

```sh
cmake --build /tmp/z23-blue-shielded-fuzz-20260928 \
  --target fuzz-blue-shielded-review-apdu -j2
ASAN_OPTIONS=detect_leaks=0 \
  /tmp/z23-blue-shielded-fuzz-20260928/fuzz-blue-shielded-review-apdu \
  -runs=1000 -max_len=4096 -timeout=15 \
  -artifact_prefix=/tmp/z23-blue-shielded-054-artifact-
```

The generated fuzz run began with an empty corpus. The focused regression
tests exercise complete six-pass transactions and rejected commands; the
fuzz count is only an additional malformed-input sample.

## Device image

The pinned C23 device build passed its image and stack gates. `.text` is
32,768 bytes, `.data` is zero, and `.bss` is 4,320 bytes, including the
2,048-byte stack reservation. The largest modeled path is the finish path
at 824 of its 1,536-byte budget. Its `.text` SHA-256 is
`4166f7b217f1368ee82bf6b397300dc59b2b6ce53e11fa0b77d74155d55aa6b7`;
the Intel HEX SHA-256 is
`67e6504dad14b00b2295a2722b3bfe363217c5f0bdf63dc313d18f094c0bed11`.
An independent source copy and a separate pinned SDK copy produced identical
`.text` and Intel HEX bytes. The ELF files differed in build metadata.

```sh
make -B -C apps/zcl-ledger/device-blue-shielded-review \
  BOLOS_SDK=/tmp/z23-blue-revoke-final-sdk \
  ARM_INCLUDE_DIR=/tmp/z23-arm-toolchain/usr/arm-none-eabi/include \
  GCCPATH=/tmp/z23-arm-toolchain/usr/bin/ CLANGPATH=/usr/bin/ -j2
```

The consensus-core seal and cyclomatic complexity cap passed. This is a
read-only shielded review image. It neither signs nor verifies shielded
recipients, amounts, or memos. It has not been installed on a physical Blue;
the tests do not establish USB timing or touchscreen behavior.
