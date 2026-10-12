<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Previous-output parser sanitizer fuzzing

Date: 2026-09-27. The host's v1-v4 previous-output selector is part of the
transparent payment preflight. A malformed previous transaction must not
change the caller's output record, and an accepted script must stay within
the supplied wire. `fuzz-zcl-previous-output` checks those invariants plus
the 10,000-byte script and 2,100,000,000,000,000-zatoshi value bounds.

Clang 22.1.6 Debug built the C23 target with libFuzzer, address sanitizer,
and undefined-behavior sanitizer. The initial corpus contained four locally
generated valid one-input/one-output wires: legacy v1, legacy v2, Overwinter
v3, and Sapling v4. Each corpus input prepended output index zero. With seed
`20260927`, `-max_len=4096`, and `-runs=100000`, the fuzzer completed 100,000
executions without a sanitizer failure or invariant violation. Its final
coverage report was 165 counters and 380 features. This run exercises the
structural parser; it does not verify chain status or consensus parity, and
its short seeds do not establish coverage of long JoinSplit or Sapling tails.

The corpus is local to the test run. Recreate its four short seeds with the
following command. The first byte is the selected output index. The common
body has a null outpoint, empty input script, a 50,000,000-zatoshi P2PKH
output, and zero lock time.

```sh
mkdir -p /tmp/zcl-prevout-corpus
common="01$(printf '%064d' 0)ffffffff00ffffffff0180f0fa02000000001976a914$(printf '11%.0s' {1..20})88ac00000000"
for version in 1 2 3 4; do
  case "$version" in
    1) prefix=01000000; suffix='' ;;
    2) prefix=02000000; suffix=00 ;;
    3) prefix=030000807082c403; suffix=0000000000 ;;
    4) prefix=0400008085202f89; suffix=000000000000000000000000000000 ;;
  esac
  printf '00%s%s%s' "$prefix" "$common" "$suffix" | xxd -r -p > "/tmp/zcl-prevout-corpus/v${version}.bin"
done
```

The version-specific wire builders in
`apps/zcl-ledger/tests/test_zcl_tx_prevout.c` independently exercise long
JoinSplit and Sapling tails. The fuzz harness accepts arbitrary raw bytes for
further corpus growth. Rebuild and rerun with:

```sh
cmake -S apps/zcl-ledger -B /tmp/zcl-prevout-fuzz \
  -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug -DZCL_LEDGER_FUZZ=ON
cmake --build /tmp/zcl-prevout-fuzz --target fuzz-zcl-previous-output -j4
/tmp/zcl-prevout-fuzz/fuzz-zcl-previous-output \
  -seed=20260927 -max_len=4096 -runs=100000 /tmp/zcl-prevout-corpus
```
