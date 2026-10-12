<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# zclassic23/mlkem

Allocation-free ML-KEM-768 (NIST FIPS 203, August 2024) for C23. It provides
key generation, encapsulation and decapsulation with the encapsulation-key and
decapsulation-key checks of FIPS 203 Sections 7.2 and 7.3. Hashing uses
`zclassic23/sha3` (SHA3-256, SHA3-512, SHAKE128, SHAKE256); wiping uses
`memory_cleanse` from `zclassic23/base`. The [zssh engine](../../../contexts/commons/modules/zssh/README.md)
calls this module for its hybrid SSH handshake. That engine has no production
session owner or accepted guest integration; module tests do not establish a
deployed SSH endpoint.

| Object | Bytes |
| --- | --- |
| Encapsulation key | 1184 |
| Decapsulation key | 2400 |
| Ciphertext | 1088 |
| Shared secret | 32 |

## Interface

`include/mlkem/mlkem.h`. The randomized entry points `zcl_mlkem768_keygen` and
`zcl_mlkem768_encaps` take a `zcl_mlkem_random_fn` callback. The module never
reads an operating-system generator: the caller must supply cryptographically
secure random bytes. The deterministic algorithms `zcl_mlkem768_keygen_internal` (seed `d || z`,
64 bytes) and `zcl_mlkem768_encaps_internal` (message `m`, 32 bytes) are
declared in `include/mlkem/mlkem_kat.h`, which production code does not include:
FIPS 203 restricts them to known-answer testing. Output buffers must not
overlap each other or any input. All functions return `enum zcl_mlkem_status`;
on failure the output buffers are zeroed.

```c
uint8_t ek[ZCL_MLKEM768_ENCAPSULATION_KEY_SIZE], dk[ZCL_MLKEM768_DECAPSULATION_KEY_SIZE];
zcl_mlkem768_keygen(my_secure_random, ctx, ek, dk);
zcl_mlkem768_encaps(my_secure_random, ctx, ek, sizeof ek, ct, sender_secret);
zcl_mlkem768_decaps(dk, sizeof dk, ct, sizeof ct, receiver_secret);
```

`examples/key_exchange.c` is a complete program.

## Constant-time behavior

| Operation on secret data | Handling |
| --- | --- |
| Reduction modulo q | Montgomery and Barrett reduction with fixed multiplications and shifts; no `/` or `%` on coefficients. |
| Compression (FIPS 203 Section 4.2.1) | `floor((2^d x + 1664) / q)` is one 64-bit multiplication by `ceil(2^35 / q)` and a shift. The multiplier is exact for every numerator below 2^22; the tests check every input for d = 1, 4, 10 against exact integer division. No division instruction receives a coefficient, which removes the KyberSlash class of timing leaks. |
| Sign-dependent adjustment | Masks derived from the sign bit; no branches. |
| NTT, inverse NTT, base multiplication, noise sampling, byte coding | Fixed loop bounds and data-independent indices. |
| Re-encryption comparison in decapsulation | XOR-accumulation over all 1088 bytes, folded to a mask. |
| Implicit rejection | The shared secret is selected between K' and SHAKE256(z \|\| c) with a byte-wise mask; the rejection secret is always computed. Decapsulation returns `ZCL_MLKEM_OK` in both cases. |
| Rejection sampling of the matrix | Depends on the public seed rho only. |
| Wiping | Secret polynomials, seeds, intermediate keys and hash buffers are cleared with `memory_cleanse`. |

Failure paths: if any sampling or SHAKE step fails, decapsulation and key
generation write no secret-derived bytes (shared secret, rejection secret,
secret vector) into the caller's buffers before the public functions zero them
and return `ZCL_MLKEM_ERR_SAMPLING`. A test-build-only fault-injection seam
(`ZCL_TESTING`; it is not compiled into release builds and is not part of the
interface) forces a failure in
the matrix sampler at the first, a middle and the last matrix row; the
noise-sampler and SHAKE failure branches are covered by reading only,
because no test forces them. The standalone package test does not define
`ZCL_TESTING`, so it skips these checks and says so; the registered harness
group `mlkem` runs them.

Limits: the module relies on arithmetic right shift of negative `int` (checked
by `static_assert`), and the C compiler is trusted not to introduce secret-
dependent branches. The sha3 module clears finalized SHA3 contexts and
the SHAKE working state and buffers with its local compiler-barrier wipe.
Its standalone tests inspect cleared SHA3 contexts; they do not prove that
all compiler-generated copies or registers are cleared, or establish a
timing guarantee.

## Resources

No heap allocation, no global mutable state (apart from the test-build fault seam). The deepest call chain
(decapsulation, re-encryption, matrix sampling, SHAKE128) uses about 12.2 KB of
automatic storage, summed from `gcc -O2 -fstack-usage`.

## Verification

`tests/test_mlkem.c` checks, with `-std=c23 -O2 -Wall -Wextra -Werror
-pedantic` under GCC 16 and clang 22, and with AddressSanitizer and
UndefinedBehaviorSanitizer:

- Barrett and canonical reduction for every `int16_t`; compression for every
  input; NTT-domain multiplication against schoolbook negacyclic multiplication.
- NIST ACVP FIPS 203 vectors (`tests/mlkem768_vectors.h`, source commit and
  JSON hashes recorded in its comment lines): 12 key generation, 12 encapsulation,
  5 valid decapsulation, 5 implicit-rejection decapsulation, 10
  decapsulation-key checks and 10 encapsulation-key checks.
- 1000 deterministic round trips; 64 single-bit ciphertext flips each yield a
  different shared secret without an error; input validation and output wiping.

Build and run (from the repository root; `-I` paths are required):

```sh
W=platform/modules
cc -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
  -I$W/mlkem/include -I$W/mlkem/src -I$W/sha3/include -I$W/base/include \
  $W/mlkem/src/*.c $W/mlkem/tests/test_mlkem.c $W/sha3/src/sha3.c \
  $W/base/src/cleanse.c -o test_mlkem
./test_mlkem            # known-answer and property tests
```
