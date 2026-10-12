<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Ledger Blue short APDU reply erasure

Date: 2026-09-28T20:01:21Z (2026-09-28T16:01:21-04:00).
Host CPU: AMD Ryzen 7 PRO 8840U w/ Radeon 780M Graphics.
Host compiler: Clang 22.1.6. ARM compiler: arm-none-eabi-gcc 16.2.0.

## Question

Can a short identity, address, or error reply leave bytes from an earlier
request or signing reply in the Blue's shared USB APDU buffer?

## Finding and change

The startup-shell test asserted that every byte after a transmitted reply
was zero. It failed on the prior main loop: the read-only command handler
wrote only its declared reply, leaving earlier bytes in the shared buffer.
The corrected loop erases the unused buffer after a successful command and
the entire buffer after a rejected command, before appending status bytes.
If a handler declares more reply bytes than the buffer can hold with its
status, the loop aborts the payment review, returns `0x6f00`, and erases
the buffer. A stub injects that oversized success claim.

The startup shell checks the buffer tail on every APDU reply, including
malformed frames. A signed-reply fixture followed by a short identity reply
confirms that no prior signature bytes remain beyond the second reply.
The reply data and status on the wire remain unchanged for valid commands.

## Reproduction

```sh
cmake --build /tmp/z23-blue-standalone-release -j2
ctest --test-dir /tmp/z23-blue-standalone-release -j1 --output-on-failure
cmake --build /tmp/z23-blue-standalone-debug -j2
ASAN_OPTIONS=detect_leaks=0 ctest --test-dir /tmp/z23-blue-standalone-debug -j1 --output-on-failure
make -C apps/zcl-ledger/device-blue-wallet BOLOS_SDK=/tmp/z23-blue-revoke-final-sdk ARM_INCLUDE_DIR=/tmp/z23-arm-toolchain/usr/arm-none-eabi/include GCCPATH=/tmp/z23-arm-toolchain/usr/bin/ CLANGPATH=/usr/bin/ -j2
```

Wallet 0.3.29 links 48,648 bytes of `.text`, zero `.data`, and 5,120 bytes
of `.bss`. Its largest named app path uses 1,112 bytes plus a 512-byte
margin within the 2,048-byte stack reserve; BOLOS frames are excluded.
Its `.text` SHA-256 is
`798c41d6eeeed3e07d9a69f5ab0dcab7af3d6300ae5a772c8be7ba5aca01dee2`;
Intel HEX SHA-256 is
`a83faa79285b72b056acfd6e047b29f5d51bbc7e3aba857f47dbe4614882b689`.
A forced rebuild from a copied source tree and separate pinned SDK copy
produced byte-identical `.text` and Intel HEX files with the same toolchain.

Serial Release and sanitized Debug suites each passed 57/57 tests. The
startup-shell case passed again in both builds after its reply-tail helper
was split below the unchanged cyclomatic cap of 15. All 33 fast lint gates
and the consensus-core seal of 554 files and 80 sections passed. Markdown
link validation scanned 528 documents and 956 local targets; inline path
validation scanned 528 documents with zero new findings.

## Limit

The tests run the app main loop against a host SDK shell. They do not prove
physical BOLOS USB timing or startup behavior. Wallet 0.3.29 remains
uninstalled after the earlier startup freeze; the installer block remains.
