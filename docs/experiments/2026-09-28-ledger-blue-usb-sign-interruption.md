<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Blue signing interruption and pending-reply erasure

Local time: 2026-09-28T03:07:40-04:00

UTC: 2026-09-28T07:07:40Z

ZCL Wallet 0.3.8 increments a command generation when a payment review is
aborted. A command rejects and wipes its reply if that generation changes
during parsing, signing, or approval-timer work. USB reset and suspend also
erase the pending APDU buffer before the event handler redraws the receive
screen. The image remains excluded from installation.

The host SDK shell injected an abort from inside the signing callback and
from the timer-clear callback after signing. Both routes returned `6985`,
cleared every reply byte, revoked approval, and did not retain a visible
payment. The app startup shell injected RESET and SUSPENDED immediately before
transmitting a mock signature reply. Both routes transmitted zeroed reply
bytes and continued to answer a subsequent identity request. These are
in-process interleaving tests, not physical interrupt timing tests. The
existing real-signature test separately verifies secp256k1 signing and host
verification; the injected callback uses a deterministic DER fixture.

With Clang 22.1.6 on an AMD Ryzen 7 PRO 8840U, the full Blue CTest suite
passed 53 of 53 cases in Release and 53 of 53 in sanitized Debug. The Debug
run used `ASAN_OPTIONS=detect_leaks=0` because LeakSanitizer cannot start
under the runner's ptrace environment; AddressSanitizer and
UndefinedBehaviorSanitizer remained active. The serial commands were:

```sh
ctest --test-dir /tmp/z23-blue-standalone-release -j1 --output-on-failure
ASAN_OPTIONS=detect_leaks=0 \
  ctest --test-dir /tmp/z23-blue-standalone-debug -j1 --output-on-failure
```

The app compiled and linked against the reviewed Blue SDK and passed its
image and static stack gates. The Intel HEX SHA-256 was
`51947f1603d7987c9781c597a622054a52f15ccffa3f67adaa79251c182ceec1`;
the extracted `.text` SHA-256 was
`78740609b61914c8fdf12102877450e2b396fb5951bcf1d11c264e5140299e22`.
The linked image had 43,016 text bytes, zero initialized-data bytes, and
5,120 BSS bytes including the reserved stack. The largest statically checked
payment-upload path was 1,048 bytes plus a 512-byte margin; BOLOS frames are
outside that calculation.

A second source checkout at commit `989367c3a` and a separately patched copy
of Blue SDK revision `3c710b4c62ad847599a2deb0932a50dd1ae4bdff`
produced the same Intel HEX and `.text` SHA-256 values above. The SDK patch
SHA-256 was
`4919fd81ba7a3a80880065aaf7898c2edd603b2586f6086a88570c73996019f6`.
Both builds used the same host and compiler toolchain, so this verifies
checkout and SDK-copy consistency, not independent machine reproducibility.
This candidate has not run on a physical Blue, and these tests do not
establish safe behavior under abrupt power loss.
